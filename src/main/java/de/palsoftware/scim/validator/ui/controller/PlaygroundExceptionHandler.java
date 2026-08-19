package de.palsoftware.scim.validator.ui.controller;

import de.palsoftware.scim.validator.ui.dto.PlaygroundExecuteResponse;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.stream.Collectors;

/**
 * Renders playground API failures as a {@link PlaygroundExecuteResponse} so the browser can show
 * them through the same {@code data.error} path it uses for target responses. Boot's default error
 * body omits {@code message} unless {@code server.error.include-message} is enabled globally, which
 * would leak exception text from every endpoint rather than just this one.
 *
 * <p>Scoped to {@link PlaygroundController}: {@link ValidationController} reports its form errors
 * through {@code BindingResult} and renders them inline instead.
 */
@RestControllerAdvice(assignableTypes = PlaygroundController.class)
public class PlaygroundExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<PlaygroundExecuteResponse> handleValidation(MethodArgumentNotValidException ex) {
        String message = ex.getBindingResult().getFieldErrors().stream()
                .map(DefaultMessageSourceResolvable::getDefaultMessage)
                .collect(Collectors.joining("; "));
        if (message.isBlank()) {
            message = "Request validation failed";
        }
        return ResponseEntity.badRequest().body(PlaygroundExecuteResponse.error(message, null, null, 0));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<PlaygroundExecuteResponse> handleUnreadableBody(HttpMessageNotReadableException ex) {
        return ResponseEntity.badRequest()
                .body(PlaygroundExecuteResponse.error("Malformed request body", null, null, 0));
    }
}
